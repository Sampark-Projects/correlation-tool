import { Badge, BadgeProps } from "@tremor/react";
import { IncidentDto } from "@/entities/incidents/model";

import {
  ExclamationCircleIcon,
  ExclamationTriangleIcon,
  InformationCircleIcon,
} from "@heroicons/react/20/solid";
import { capitalize } from "@/utils/helpers";
import {getIncidentSeverityIconAndColor} from "@/entities/incidents/lib/utils";

interface Props {
  severity: IncidentDto["severity"];
  size?: BadgeProps["size"];
}

export function IncidentSeverityBadge({ severity, size = "xs" }: Props) {
  const {icon, color} = getIncidentSeverityIconAndColor(severity);
  // Tremor's "orange" is the brand green in this app; high severity keeps a real
  // orange, which Tremor can only take as a hex (that would paint text and
  // background the same color), so style the badge explicitly instead
  const isHex = color.startsWith("#");

  return (
    <Badge
      color={isHex ? "gray" : color}
      className={`capitalize ${
        isHex ? "!bg-[#ffedd5] !text-[#9a3412] !ring-[#fdba74]" : ""
      }`}
      size={size}
      icon={icon}
    >
      {capitalize(severity)}
    </Badge>
  );
}
